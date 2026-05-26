- It's based on PostgreSQL, it's backend as service

# Setup
- Go to supabase, create new project, bla bla bla
- Add your table, columns, then rows
- Now back in your terminal, install the [supabase.js library](https://supabase.com/docs/reference/javascript/introduction)
```
npm install @supabase/supabase-js
```
- It helps us with 
![[Screenshot 2026-05-26 104610.png]]
- If you want to learn more about how things work under the hood check [this video](https://www.youtube.com/watch?v=T-qAtAKjqwc) made by Supabase themselves 

## Initializing our JS Client ^
- Create a `.js` file mainly called : `supabase-client.js`
- Import :
```js
import { createClient } from "@supabase/supabase-js"
```
- Then your `Env variabels`, which since we're using `Vite` need to follow this naming convention : `VITE_<name>`
```js
import { createClient } from "@supabase/supabase-js"

// import.meta.env instead of process.env because of Vite
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseKey = import.meta.env.VITE_SUPABASE_KEY  

const supabase = createClient(supabaseUrl, supabaseKey)

export default supabase
```

- Just like that, now we have a connection to the supabase client

> You can find your Project URL and API anon Key on the project dashboard
# Persistence
