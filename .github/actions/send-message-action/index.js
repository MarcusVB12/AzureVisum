const args = require('minimist')(process.argv.slice(2))
const convert = require('xml-js');
const fs = require('node:fs');
require('dotenv').config()
const ORGANIZATION = process.env.DEVOPS_ORGANIZATION
const PROJECTS = process.env.DEVOPS_PROJECTS?.split(';').map((project) => project.trim())
const API_VERSION = '7.2-preview'
const LOGIN = 'basic'
const URL = `https://dev.azure.com/${ORGANIZATION}/{project}/_apis/`
const STATE_TO_VERIFY = ['Done']
let TOKEN = process.env.DEVOPS_TOKEN_DEFAULT
let projectName = PROJECTS?.[0]

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
    console.log(url)
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
        id: `${workItem.fields['System.WorkItemType']?.[0]}-${workItem.id}`,
        state: workItem.fields['System.State']
    }))
}
function veryBranchs(workItems, branchsNumber){
    //verificar branchs com merge baseado na sprint
    //remover qualquer caracter que não seja numero
    //verificar se a branch como merge bate com o items do azure 
    //montar uma lista com as branchs em aberta
    //retorna para o adam
    //montar o envio para galera
    
    const workItemsToVerifyGit = wrappedWorkItems.filter((workItem) => STATE_TO_VERIFY.includes(workItem.state)) // filtrando lista por done

}

async function init() {
    //pegar a lista de branchs com status merges de prrod
    const fileName = (args?.fileName)?.toString()
    console.log('fileName ' + fileName);
    const currentSprintId = (await getSprint())?.value?.[0]?.id
    const workItemsOfCurrentSprint = (await getWorkItemsWithSprint(currentSprintId))?.workItemRelations.map((workItem) => workItem.target.id)
    const workItemsContentOfCurrentSprint = (await getWorkItemsWithIdList(workItemsOfCurrentSprint, ['System.WorkItemType', 'System.State']))?.value
    veryBranchs(workItemWrapper(workItemsContentOfCurrentSprint));
    //console.log(wrappedWorkItems)
    //console.log(workItemsToVerifyGit)
}
init()