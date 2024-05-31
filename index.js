import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import cors from "cors";



const app = express();
const saltRounds = 10;
dotenv.config();
const port = process.env.PORT;

app.get('/', (req, res) => {
    res.send("<h1>Hello from the backend</h1>")
})

app.listen(port, () => {
    console.log(`Server started on port ${port}`)
})