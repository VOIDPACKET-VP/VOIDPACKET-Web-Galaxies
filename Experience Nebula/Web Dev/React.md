# Quizzical
![[Screenshot 2026-05-26 102010.png]]

- If you have an async function : USE `useEffect`, react can't do that for you

# API
- If you're using an API, you have to add the following
```js
// Since we're using an API, we have to cover the wait for the response and errors if any

const [loading, setLoading] = useState(true)
const [error, setError] = useState(null)
```
- Make sure you know exactly the data format that stupid API will give you (e.g. the names, array ?, only objects ? )
- People have some stupid API rules sometimes hhhhhhhh