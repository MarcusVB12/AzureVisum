const args = require('minimist')(process.argv.slice(2))
const convert = require('xml-js');
const fs = require('node:fs');
const { Console } = require('node:console');
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

async function getWorkItemsWithSprint(sprintId) {
    const url = URL.replace('{project}', projectName) + `work/teamsettings/iterations/${sprintId}/workitems?api-version=${API_VERSION}`
    let headers = new Headers()
    headers.set('Authorization', 'Basic ' + btoa(`${LOGIN}:${TOKEN}`))
    headers.set('Content-Type', 'application/json-patch+json')
    const request = new Request(url, {
        method: "GET",
        headers: headers
    })
    const response = await fetch(request)
    if (response.status != 200) {
        return
    }
    const responseString = await response.text()
    return JSON.parse(responseString)
}

async function getSprint() {
    const url = URL.replace('{project}', projectName) + `work/teamsettings/iterations?$timeframe=current&api-version=${API_VERSION}`
    let headers = new Headers()
    headers.set('Authorization', 'Basic ' + btoa(`${LOGIN}:${TOKEN}`))
    headers.set('Content-Type', 'application/json-patch+json')
    const request = new Request(url, {
        method: "GET",
        headers: headers
    })
    const response = await fetch(request)
    if (response.status != 200) {
        return
    }
    const responseString = await response.text()
    return JSON.parse(responseString)
}

async function getWorkItemsWithIdList(workItems, fields, filters) {
    const url = URL.replace('{project}', projectName) + `wit/workitems?ids=${workItems.join(',')}&api-version=${API_VERSION}${fields ? `&fields=${fields?.join(',')}` : ''}`
    let headers = new Headers()
    headers.set('Authorization', 'Basic ' + btoa(`${LOGIN}:${TOKEN}`))
    headers.set('Content-Type', 'application/json-patch+json')
    const request = new Request(url, {
        method: "GET",
        headers: headers
    })
    const response = await fetch(request)
    if (response.status != 200) {
        return
    }
    const responseString = await response.text()
    return JSON.parse(responseString)
}

function workItemWrapper(workItems) {
    return workItems.map((workItem) => ({
        name: `${workItem.fields['System.WorkItemType']?.[0]}-${workItem.id}`,
        state: workItem.fields['System.State']
    }))
}


function veryBranchs(wrappedWorkItems, branchs){
    const branchsNames = branchs.filter((item) => item.name.startsWith('F-') || item.name.startsWith('T-'));
    console.log('branchsNames' + branchsNames);
    
    const workItemsToVerifyGit = wrappedWorkItems.filter((workItem) => (STATE_TO_VERIFY.includes(workItem.state)));
    console.log('workItemsToVerifyGit' + workItemsToVerifyGit);
    
    console.log('aaa' + filterObjects(workItemsToVerifyGit, branchsNames, 'name'));  
}

function filterObjects(list1, list2, key) {
    return list1.filter(item1 => 
        list2.some(item2 => item2[key].toString().replace(/[^0-9]/g, '') === item1[key].toString().replace(/[^0-9]/g, ''))
    );
}

async function init() {
    
    const branchs = await rest();

    const currentSprintId = (await getSprint())?.value?.[0]?.id;
    const workItemsOfCurrentSprint = (await getWorkItemsWithSprint(currentSprintId))?.workItemRelations.map((workItem) => workItem.target.id);
    const workItemsContentOfCurrentSprint = (await getWorkItemsWithIdList(workItemsOfCurrentSprint, ['System.WorkItemType', 'System.State']))?.value;
    const workItemsWrapped = workItemWrapper(workItemsContentOfCurrentSprint);
    const t = veryBranchs(workItemsWrapped, branchs);
}

init()