# Notes on The Mobile App project at Scrimba which uses Firebase

- First create a project, then we copy these code snippets given by Firebase to us for each project :
	- `  import { initializeApp } from "https://www.gstatic.com/firebasejs/12.11.0/firebase-app.js";`
	- `const firebaseConfig = {};`
	- `const app = initializeApp(firebaseConfig);`

- Then we add the following :
```
import { getDatabase, ref, push } from "https://www.gstatic.com/firebasejs/10.7.2/firebase-database.js"

const firebaseConfig = {
    databaseURL: "https://birthday-app-75b25-default-rtdb.europe-west1.firebasedatabase.app/"
}

const database = getDatabase(app)
const referenceInDB = ref(database, "birthdays")
```

- So our full setup will be :
  ```
  import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.2/firebase-app.js"

import { getDatabase, ref, push } from "https://www.gstatic.com/firebasejs/10.7.2/firebase-database.js"

const firebaseConfig = {
  databaseURL: "https://birthday-app-75b25-default-rtdb.europe-west1.firebasedatabase.app/"
}

const app = initializeApp(firebaseConfig)
const database = getDatabase(app)
const referenceInDB = ref(database, "birthdays") // This is the reference which is basically where we want to store our data, it takes 2 params : the db and a name

// Then to add any data to our DB we use that push function we imported 
push(<reference>, <data_to_push>);
  ```
- 