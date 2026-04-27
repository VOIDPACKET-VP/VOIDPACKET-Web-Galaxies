# AI request 
- When talking with AI models, we assume the role of `user` and the AI replies with the role `assistant`
-  Obviously AI API request must be handled by the BACKEND
## We start with 
```
import OpenAI from "openai"  // Importing THE AI CLIENT


// Initialising the AI CLIENT
const openai = new OpenAI({
  apiKey: process.env.AI_KEY,
  baseURL: process.env.AI_URL
})
```
- The `openai` words used can be changed depending on the AI model your using

## Now we need The message (prompt)
```
const userPrompt = "bla bla bla"

const userMessage = {
	role: "user",
	content: userPrompt
}

const response = await openai.chat.completions.create({
	model: process.env.AI_MODEL,
	messages: [userMessage]   // it expects an array
})
```
- We used `chat.completions` API because it's an Text generator, and it's widely used, it's not limited to just chat bots

## Get the response 
- A response will be something like this 
```
{
    "id": "aowdnawodmoawmdoa",
    "object": "chat.completion",
    "created": 8189189199819,
    "model": "awd9awijd",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "bla bla bla bla bla bla",
                "refusal": null,
                "annotations": []
            },
            "finish_reason": "stop"
        }
    ],
    "usage": {
        "prompt_tokens": 16,
        "completion_tokens": 2431,
        "total_tokens": 2447,
        "prompt_tokens_details": {
            "cached_tokens": 0,
            "audio_tokens": 0
        },
        "completion_tokens_details": {
            "reasoning_tokens": 1856,
            "audio_tokens": 0,
            "accepted_prediction_tokens": 0,
            "rejected_prediction_tokens": 0
        }
    },
    "service_tier": "default",
    "system_fingerprint": null
}
```
- so to get only the content :
```
console.log(response.choices[0].message.content)
```

## Tokens
- So AI models don't process Messages they process Tokens
- A token can represent a single character, a whole word, or just a space
- So knowing that we can actually Limit the AI's response to a specified amount of TOKENS
- SYNTAX :
```
Inside the AI Response object, we add max_tokens or max_completion_tokens
depending on what AI model we're using

const response = await openai.chat.completions.create({
	model: process.env.AI_MODEL,
	messages: [userMessage],
	max_tokens: 256
}) 
```
- Ai Models will cut off the response the moment it reaches the max tokens, so it's best to modify our prompt 

## The messages array
- Remember when i said it expects an array, but WHY ?
- When you're using Ai models, that usage feels like a conversation because we think AI is remembering our previous messages, but in reality AI Models have no way of remembering, so How do they Remember ?
	- They do so by sending the previous user messages and their responses with the new user message
	- And this cycle repeats itself
- That's why it's an array
- So we get the response, we push it into the message array, then we make a second AI API request, and so on

## System Message
- So in our prompts we specify what we want, and how to give us what we want, right ?
	- So the Model doesn't know the difference between what the user wants and how to behave
- That's where the `system` message comes in, it looks similar to the user's message or AI's response :
```
{
	role: "system",
	content: "bla bla bla"
}
```
![[Screenshot 2026-04-27 133719.png]]

- System prompts are how the best Prompt engineers get the most from their models, here are some prompts :
	- [BigPromptLibrary](https://github.com/0xeb/TheBigPromptLibrary/tree/main/SystemPrompts)
	- [SystemPrompts](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools)

## Converting MARKED into HTML
- We use a library called : `marked`
### We start with importing it 
- `import { marked } from "marked"`
- Then you use a function called `parse`
	- `marked.parse( <what to convert> )`
- We will have to DOM Purify it so that we prevent from XSS, we do that using a library called : `DOMPurify` 
	- `import DOMPurify from "dompurify"` 
	- `const clean = DOMPurify.sanitize(dirty)`
	- [DOMPurify](https://github.com/cure53/DOMPurify)
- SO first you parse then Sanitize

## Better UX with Streaming
- So streaming responses is when you ask the ai and then you say the response getting rendered live instead of a full chunk of text
- It works by The API sending multiple chunks of the response chunk by chunk

- SYNTAX :
```
inside the ai response Object : openai.chat.completions.create({})
we add : 
	stream: true
```
- This means we can loop over those chunks, but since they are arriving in real time via a server we have to use `async JS` 
```
for await (const chunk of stream) {
	<code>
}
```
- EXAMPLE :
```
for await (const chunk of stream) {
	console.log(chunk.choices[0].delta.content)
}
```
- REMEMBER, each of these chunks are separate so we need to reconstruct it 
- So here is what you'll mostly need to do :
   1. Enable streaming by adding stream: true to the request
   2. Loop over the stream using for await...of syntax
   3. Extract content from each chunk
   4. Accumulate streamed text chunks into a single string
   5. Convert that accumulated Markdown into HTML
   6. Sanitize the HTML
   7. Render it progressively as the stream updates

## Shot Prompting
- You know when you're trying to explain something to the AI, but you felt like it's better to show instead of tell. Comes SHOT PROMPTING :
	- A `shot` is just an example
	- `Zero shot` means no example
	- `Few shot` means couple of examples
- You would generally add them in the messages array, which means they would also affect the token usage thus slightly more cost, so you have to think about this.

## Temperature and Top P
- Every time the model generates text, it's choosing between many possible next tokens : these tokens have a probability beside them (chance of them being used etc.)
- So temperature is how risky the model will be when choosing its next word
	- Higher Temperatures => Creative risk
	- Lower Temperature => Model plays it safe
- This only changes how boldly it chooses, not what it knows
- The temperature param goes again inside the `ai response` object

- TOP P : remember when i said each token has it's probability value of getting chosen, well `Top P` controls whether to consider every token or less :
	- default value is : `1.0` 
	- If for example `top_p: 0.9` => it will ignore the least likely options and so on


| Temperature            | Top P                          |
| ---------------------- | ------------------------------ |
| Makes the model bolder | Makes the model more selective |
![[Screenshot 2026-04-27 174002.png]]

## Responses API
- So far we've used the `chat completions` API
- `OpenAI` at the moment uses `RESPONSE API` 
- So instead of `openai.chat.completions.create` , we do :
	- `openai.responses.create`
- And instead of `messages: <message>` we use : `input: <message>`
- And finally instead of : `response.choices[0].messages.content`, we use : `response.output_text`
- Why this one is better you might ask ?
	- Well, it gives us features `chat completions API` doesn't have, mainly the `Web Search feature`, see Ai models they only know what they're taught, which stops at a certain time it's called `knowledge cutoff` : the Model stopped training starting from that date.
	- So if you ask it about something happened yesterday and it's cutoff happened a month ago, it will hallucinate ...
	- So `Responses API` has the ability to search, if it doesn't know something it will search the web to find similar topics etc. We enable this feature like this :
```
/// inside the ai response object we add
  tools: [{ type: "web_search" }]
```

## JSON output
- So we use JSON outputs when we wanna use that data in our code, let's see how we can achieve that
### Make our AI return JSON 
- There are couple of ways :
	1. Precising the response Structure :
		1. Add it as a rule inside the system message
			- This can cause some problems with older Models : they will append `<```>JSON <JSON DATA> <```>` this is not a valid JSON FORMAT
		2. Add a Shot
	2. The best way is to use the `response_format: <JSON_schema>` param if using `chat completions` or if using `responses API` 
```
text: {
	format: <JSON_schema>
}
```
- This time we are forcing the Model to use our JSON schema instead of hoping 
- You don't need to be an expert 

