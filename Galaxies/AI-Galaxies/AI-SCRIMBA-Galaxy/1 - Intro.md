# **AI models**
- They are not intelligent or conscience, they are great at recognizing and generating patterns
- They are also called `LLM`
- They have to be hosted somewhere : on your pc, but for them to run smooth we run them using `Model Provider` : services that will run our AI models on their servers and gives us back an API which we can use to talk with our AI using code
### *What we need to send a request*
- Destination : e.g. OpenAI
- AI Model : gpt-5-nano
- Identity and Permissions : OpenAI API Key

- We'll be using `openai client` which will take care of :
	- Formats requests correctly
	- Attaches our API key
	- Handles responses and errors
	- Saves us from writing raw HTTP calls
# **Let's Start**
- We first need to import `OpenAI`library in our main JS file : `import OpenAI from "openai"` 
- Same thing for our `.env` file where we stored our :
	- `AI_URL = https://api.groq.com/openai/v1`
	- `AI_KEY = Check the Groq API File (can't put it here)`
	- `AI_MODEL = openai/gpt-oss-20b`
- IDK how this really works, but alhamdulillah SCRIMBA is taking care of it
- HERE I REALIZED I FORGOT A LOT ABOUT JS, so we'll be back 