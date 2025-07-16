const args = require("minimist")(process.argv.slice(2));
const fs = require("node:fs");
const core = require('@actions/core');
const github = require('@actions/github');
require("dotenv").config();
async function sendMessage(mSlackUser, slackGitHubToken, mUserEmailToChannel) {
  try{
        mUserEmailToChannel = JSON.parse(mUserEmailToChannel);
        mSlackMessage = await getSlackMessage(mSlackUser, mUserEmailToChannel);
        console.log(mSlackMessage);
        console.log(mUserEmailToChannel);
        for(const userEmail in mSlackMessage){
            let values = mSlackMessage[userEmail];
            let token = slackGitHubToken;
            let channel = mUserEmailToChannel[userEmail]?.channelId;
            console.log(mUserEmailToChannel[userEmail]);
            const url = "https://slack.com/api/chat.postMessage";
            if (!channel) {
                console.warn(`Chave ${userEmail} não encontrada no userMap. Pulando... Channel: ${channel} `);
                continue; 
            }
            let headers = new Headers();
            headers.set("Authorization", "Bearer " + token);
            headers.set("Content-Type", "application/json");
            const request = new Request(url, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({
                    channel,
                    blocks: JSON.parse(JSON.stringify(values?.blocks))
                })
            });
            try {
                const response = await fetch(request);
                const responseString = await response.text();
                console.log('Resposta da API do Slack:', responseString);
                console.log('deploySuccess : ' + responseString);
            } catch (error) {
                console.error("Erro ao enviar mensagem para o Slack:", error);
            }
        };
    
    }catch(e){
        return console.log(e.stack);
    }
}

async function getSlackMessage(slackUsersMap, mUserEmailToChannel){
    const mapData = {};
    let allBranches = [];
    for(const userEmail of Object.keys(slackUsersMap)) {
        let values = slackUsersMap[userEmail];
        mapData[userEmail] = message(values);
        allBranches = allBranches.concat(values);
    };

    for(const userEmail of Object.keys(mUserEmailToChannel)) {
        const userScope = mUserEmailToChannel[userEmail]?.scope;

        if(userScope === 'all'){
            mapData[userEmail] = message(allBranches);
        }
    }  

    return mapData;
}

function message(values) {
    let message = [];
  
    values.forEach( item => {
        message.push({
            "type": "text",
            "text": `🟢 [Número de referência: ${item.name}]\n`
        })
    })
    let rich_text = [{
        "type" : "rich_text_preformatted",
        "elements" : message
    }]
    return {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "emoji": true,
                    "text": "Branchs para deleção"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*As features a seguir estão como dones porém suas branchs no git ainda existem e podem ser deletadas. 🫡🫡*"
                }
            },
            {
                "type": "rich_text",
                "elements": rich_text
            },
            {
                "type": "divider"
            }
        ]
    };
}
module.exports = { sendMessage };