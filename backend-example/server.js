import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 4000;
const mongoURL = "mongodb://localhost:27017";
const dbName = "quirknotes";

// Connect to MongoDB
let db;

async function connectToMongo() {
  const client = new MongoClient(mongoURL);

  try {
    await client.connect();
    console.log("Connected to MongoDB");

    db = client.db(dbName);
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

connectToMongo();

// Open Port
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });

// Collections to manage
const COLLECTIONS = {
    notes: "notes",
    users: "users",
  };

// Register a new user
app.post("/registerUser", express.json(), async (req, res) => {
    try {
      const { username, password } = req.body;

      // Basic body request check
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password both needed to register." });
      }

      // Checking if username does not already exist in database
      const userCollection = db.collection(COLLECTIONS.users);
      const existingUser = await userCollection.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: "Username already exists." });
      }

      // Creating hashed password (search up bcrypt online for more info)
      // and storing user info in database
      const hashedPassword = await bcrypt.hash(password, 10);
      await userCollection.insertOne({
        username,
        password: hashedPassword,
      });

      // Returning JSON Web Token (search JWT for more explanation)
      const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });
      res.status(201).json({ response: "User registered successfully.", token });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Log in an existing user
app.post("/loginUser", express.json(), async (req, res) => {
    try {
      const { username, password } = req.body;

      // Basic body request check
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password both needed to login." });
      }

      // Find username in database
      const userCollection = db.collection(COLLECTIONS.users);
      const user = await userCollection.findOne({ username });

      // Validate user against hashed password in database
      if (user && (await bcrypt.compare(password, user.password))) {
        const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });

        // Send JSON Web Token to valid user
        res.json({ response: "User logged in succesfully.", token: token }); //Implicitly status 200
      } else {
        res.status(401).json({ error: "Authentication failed." });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Post a note belonging to the user
app.post("/postNote", express.json(), async (req, res) => {
    try {
      // Basic body request check
      const { title, content } = req.body;
      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are both required." });
      }

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized.");
        }

        // Send note to database
        const collection = db.collection(COLLECTIONS.notes);
        const result = await collection.insertOne({
          title,
          content,
          username: decoded.username,
        });
        res.json({
          response: "Note added succesfully.",
          insertedId: result.insertedId,
        });
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Retrieve a note belonging to the user
app.get("/getNote/:noteId", express.json(), async (req, res) => {
    try {
      // Basic param checking
      const noteId = req.params.noteId;
      if (!ObjectId.isValid(noteId)) {
        return res.status(400).json({ error: "Invalid note ID." });
      }

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized.");
        }

        // Find note with given ID
        const collection = db.collection(COLLECTIONS.notes);
        const data = await collection.findOne({
          username: decoded.username,
          _id: new ObjectId(noteId),
        });
        if (!data) {
          return res
            .status(404)
            .json({ error: "Unable to find note with given ID." });
        }
        res.json({ response: data });
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Retrieve all notes belonging to the user
app.get("/getAllNotes", express.json(), async (req, res) => {
    try {
      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized."); // 401 is sent when the user is not authorized, i.e. the JWT is invalid.
        }

        // Find all notes belonging to user
        const collection = db.collection(COLLECTIONS.notes); // we bring in the notes collection
        const data = await collection // we find all the notes that belong to the user, which we know because each note has a username field
          .find({ username: decoded.username }) // this makes it possible that the user can only see their own notes and not the notes of other users.
          .toArray(); // we convert the cursor to an array
        res.json({ response: data }); // we send the array of notes back to the user in json format. The requested format is the same as the one we used to store the notes in the database so we can use it directly
      }); // the 200 status code is sent implicitly
    } catch (error) {
      res.status(500).json({ error: error.message }); // general server errors
    }
});

// Delete a note belonging to the user
app.get("/deleteNote/:noteId", express.json(), async (req, res) => {
    try {
      // Basic param checking
      const noteId = req.params.noteId;
      if (!ObjectId.isValid(noteId)) { // we check if the noteId is valid
        return res.status(400).json({ error: "Invalid note ID." });
      }

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized."); // we check if the user is authorized to delete the note
        }

        // Find note with given ID
        const collection = db.collection(COLLECTIONS.notes); //these steps are the same as in the getNote function
        const data = await collection.findOneAndDelete({ // i found this function in the mongo documentation
          username: decoded.username,
          _id: new ObjectId(noteId),
        });
        if (!data) {
          return res
            .status(404)
            .json({ error: "Unable to find note with given ID." });
        }

        res.json({
            response: `Document with ID ${noteId} deleted succesfully.`,
        });

      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Edit a note belonging to the user
app.get("/editNote/:noteId", express.json(), async (req, res) => {

    try {
      // Basic param checking
      const noteId = req.params.noteId;
      if (!ObjectId.isValid(noteId)) { // we check if the noteId is valid
        return res.status(400).json({ error: "Invalid note ID." });
      }

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized."); // we check if the user is authorized to edit the note
        }

      //check if the title and/or content are present, because we need at least one of them to edit the note
        if (!req.body.title && !req.body.content) {
            return res.status(400).json({ error: "A title or content are needed to update the note" });
        }

        // Find note with given ID
        const collection = db.collection(COLLECTIONS.notes); //these steps are the same as in the getNote function

        const originalNote = await collection.findOne({
            username: decoded.username,
            _id: new ObjectId(noteId),
        }); // I want to get the original note to save the original title and content if the user doesn't provide them in the request body
            //i don't know how else I can get the original info to stay the same otherwise if the user doesn't update it
        if (!originalNote) {
          return res
            .status(404)
            .json({ error: "Unable to find note with given ID." });
        }

        const data = await collection.findOneAndUpdate({
          username: decoded.username,
          _id: new ObjectId(noteId),
        },
        {
            $set: {
                title: req.body.title || originalNote.title,
                content: req.body.content || originalNote.content,
            },
        }
       );

        res.json({
            response: `Document with ID ${noteId} properly updated.`,
        });

      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
