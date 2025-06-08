import { initializeApp } from "firebase/app"
import { getAuth } from "firebase/auth"
import { getFirestore } from "firebase/firestore"

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBwzMVDW-lHkyHetoqJibjGBxR08m4SedI",
  authDomain: "sample-firebase-ai-app12-b61b9.firebaseapp.com",
  projectId: "sample-firebase-ai-app12-b61b9",
  storageBucket: "sample-firebase-ai-app12-b61b9.firebasestorage.app",
  messagingSenderId: "419784799244",
  appId: "1:419784799244:web:55ad22867fc54177bf2a29"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig)
const auth = getAuth(app)
const db = getFirestore(app)

export { auth, db }
