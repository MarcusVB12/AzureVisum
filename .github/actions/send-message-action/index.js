require('dotenv').config()
const { sendMessage } = require('./sendSlackMessage.js');
const ORGANIZATION = process.env.DEVOPS_ORGANIZATION
const API_VERSION = '7.2-preview'
const LOGIN = 'basic'
const URL = `https://dev.azure.com/${ORGANIZATION}/_apis/`
const STATE_TO_VERIFY = ['Done']
const SLACK_GITHUB_TOKEN = process.env.SLACK_GITHUB_TOKEN;
const SLACKUSERSMAP_BYEMAIL = process.env.SLACKUSERSMAP_BYEMAIL;
const DEVOPS_TOKEN_DEFAULT = process.env.DEVOPS_TOKEN_DEFAULT
const GIT_BRANCHES = process.env.GIT_BRANCHES 
    ? process.env.GIT_BRANCHES.split(',').map(branch => branch.trim()) 
    : [];
    
let branchsToMenssage = new Map();

function filterBranchs(branchs) {
    if (!Array.isArray(branchs)) {
        console.error('Erro: branchs não está como um array', branchs);
        return [];
    }

    return branchs.map(branch => {
        const match = branch.match(/\d+/g);
        return match ? match.join('') : null; 
    }).filter(Boolean); 
}


async function processInBatches(array, processFunction) {
    const uniqueItems = [...new Set(array)];

    for (const item of uniqueItems) {
        await processFunction([item]);
    }
}

   
async function processBatch(branchs) {
    const workItemsResponse = await getWorkItemsWithIdList(branchs, ['System.WorkItemType', 'System.State', 'System.AssignedTo']);

    if (!workItemsResponse || !workItemsResponse.value || !Array.isArray(workItemsResponse.value)) {
        return;
    }

    const workItemsContentOfCurrentSprint = workItemWrapper(workItemsResponse.value);
    veryBranchsDone(workItemsContentOfCurrentSprint);
}

async function getWorkItemsWithIdList(workItems, fields) {
    if (!workItems.length) {
        console.log("Nenhum workItem para buscar.");
        return { value: [] };
    }

    let allResults = [];

    for (const workItem of workItems) {
        const url = `${URL}wit/workitems?ids=${workItem}&api-version=${API_VERSION}${fields ? `&fields=${fields?.join(',')}` : ''}`;

        let headers = new Headers();
        headers.set('Authorization', 'Basic ' + btoa(`${LOGIN}:${DEVOPS_TOKEN_DEFAULT}`));
        headers.set('Content-Type', 'application/json-patch+json');

        const request = new Request(url, { method: "GET", headers: headers });

        try {
            const response = await fetch(request);
            if (response.status !== 200) {
                continue;
            }

            const responseJson = await response.json();

            if (responseJson?.value && Array.isArray(responseJson.value)) {
                allResults.push(...responseJson.value);
            } else {
                console.warn("Aviso: Resposta da API não contém um array válido.");
            }
        } catch (error) {
            console.error("Erro ao buscar work items:", error);
        }
    }

    return { value: allResults };
}

function workItemWrapper(workItems) {
    if (!workItems || !Array.isArray(workItems)) {
        console.error("Erro: workItems está undefined ou não é um array", workItems);
        return [];
    }

    return workItems.map(workItem => {
        const assignedTo = workItem.fields?.['System.AssignedTo'];
        const assignedEmail = assignedTo?.uniqueName || 'Sem responsável';

        return {
            name: `${workItem.fields?.['System.WorkItemType'] || 'Desconhecido'}-${workItem.id}`,
            state: workItem.fields?.['System.State'] || 'Estado Indefinido',
            email: assignedEmail
        };
    });
}

function veryBranchsDone(wrappedWorkItems) {
    let items = wrappedWorkItems.filter(workItem => STATE_TO_VERIFY.includes(workItem.state));

    if (!items.length) {
        return;
    }

    branchsToMenssage = items.reduce((acc, item) => {
        acc[item.email] = acc[item.email] || [];

        if (!acc[item.email].some(existingItem => existingItem.name === item.name)) {
            acc[item.email].push({ name: item.name, state: item.state });
        }

        return acc;
    }, branchsToMenssage || {});
}

async function init() {
    const branchs = filterBranchs(GIT_BRANCHES);

    await processInBatches(branchs, processBatch); // Aguarda todas as batches serem processadas

    // Enviar a mensagem somente após processamento completo
    sendMessage(branchsToMenssage, SLACK_GITHUB_TOKEN, SLACKUSERSMAP_BYEMAIL);
}

init();