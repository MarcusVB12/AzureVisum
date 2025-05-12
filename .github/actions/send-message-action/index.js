require('dotenv').config()
const ORGANIZATION = process.env.DEVOPS_ORGANIZATION
const PROJECTS = process.env.DEVOPS_PROJECTS?.split(';').map((project) => project.trim())
const API_VERSION = '7.2-preview'
const LOGIN = 'basic'
const URL = `https://dev.azure.com/${ORGANIZATION}/{project}/_apis/`
const STATE_TO_VERIFY = ['Done']

let TOKEN = process.env.DEVOPS_TOKEN_DEFAULT
let projectName = PROJECTS?.[0]
let TOKENGH = process.env.GH_TOKEN
let branchsToMenssage = [];

async function rest() {
    let headers = new Headers();
    // headers.set("Authorization", "Bearer " + TOKENGH);
    headers.set("Content-Type", "application/json");

    const request = new Request('https://api.github.com/repos/MarcusVB12/AzureVisum/branches', {
      method: "GET",
      headers: headers
    });

    const response = await fetch(request);
 
    const responseString = await response.text();

    return JSON.parse(responseString);
}

function filterBranchs(branchs){
    return branchs.filter((item) => item.name.startsWith('F-') || item.name.startsWith('T-')).map((item) => item.name.replace(/F-|T-/g, ''));
}

async function processInBatches(array, batchSize, processFunction) {
    for (let i = 0; i < array.length; i += batchSize) {
      const batch = array.slice(i, i + batchSize);
      await processFunction(batch);
    }
}
   
async function processBatch(branchs) {

    const workItemsContentOfCurrentSprint = workItemWrapper((await getWorkItemsWithIdList(branchs, ['System.WorkItemType', 'System.State', 'System.AssignedTo']))?.value);

    veryBranchsDone(workItemsContentOfCurrentSprint);
}  

async function getWorkItemsWithIdList(workItems, fields) {
    const url = URL.replace('{project}', projectName) + `wit/workitems?ids=${workItems.join(',')}&api-version=${API_VERSION}${fields ? `&fields=${fields?.join(',')}` : ''}`;
    let headers = new Headers();

    headers.set('Authorization', 'Basic ' + btoa(`${LOGIN}:${TOKEN}`));
    headers.set('Content-Type', 'application/json-patch+json');

    const request = new Request(url, {
        method: "GET",
        headers: headers
    });

    const response = await fetch(request);
    
    if (response.status != 200) {
        return
    };

    const responseString = await response.text();
    
    return JSON.parse(responseString);
}

function workItemWrapper(workItems) {
    return workItems.map((workItem) => ({
        name: `${workItem.fields['System.WorkItemType']?.[0]}-${workItem.id}`,
        state: workItem.fields['System.State'],
        email: workItem.fields['System.AssignedTo']?.uniqueName
    }));
}

function veryBranchsDone(wrappedWorkItems){
    let items = wrappedWorkItems.filter((workItem) => (STATE_TO_VERIFY.includes(workItem.state)));

    if(!items){
        return;
    }

    branchsToMenssage.push(items);
}

async function init() {
    
    const branchs = filterBranchs(await rest());
    
    await processInBatches(branchs, 200, processBatch);

    console.log('Branchs to menssage:', branchsToMenssage);
}

init();