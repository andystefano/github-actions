require('dotenv').config();

const { WebClient } = require('@slack/web-api');

const token = process.env.SLACK_BOT_TOKEN;
const channelId = 'C08VC91C8RE'; // Reemplaza con tu channel ID real

const slackClient = new WebClient(token);

async function run() {
  try {
    let hasMore = true;
    let cursor;

    while (hasMore) {
      const result = await slackClient.conversations.history({
        channel: channelId,
        limit: 200,
        cursor,
      });

      for (const message of result.messages) {
        if (message.bot_id) {
          console.log(`🗑️ Eliminando mensaje del bot: ${message.ts}`);
          await slackClient.chat.delete({
            channel: channelId,
            ts: message.ts,
          });
        }
      }

      hasMore = result.has_more;
      cursor = result.response_metadata?.next_cursor;
    }

    console.log('✅ Mensajes del bot eliminados.');
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

run();
