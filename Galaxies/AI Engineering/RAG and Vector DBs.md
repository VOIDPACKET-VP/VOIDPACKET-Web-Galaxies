# Embeddings
- It's the language of AI
- It's a mathematical concept that refers to placing an Object into a different space 
	- Like taking a word (string) and changing it into numbers
	- It does that interpreting a huge amount of data, this data is represented as numerical values (floating point numbers) which are called `Vectors` 
- So embeddings are just vectors
- So AI would know if words have a relation by seeing how close the vectors of those words are, those close words form `Clusters`. AI uses vectors that are represented in 100 if not 1000 of dimensions 
![[Screenshot 2026-04-29 183356.png]]
## How embeddings are used in the REAL WORLD
![[Screenshot 2026-04-29 183545.png]]

## Create Embeddings (Text Embedding)
- You will need to read documentations of the AI API your using, it's a bit similar to what we've seen in the AI fundamentals
- For OPENAI, it's something like this 
```
async function main() {
  const embedding = await openai.embeddings.create({
    model: "text-embedding-ada-002",
    input: content,
  });
  console.log(embedding.data);
}
main();
```

## Vectors DBs
- They have the capacity to store and retrieve embeddings quickly and at scale 