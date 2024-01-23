import express from "express";
import productsRouter from "./routes/products.router.js";
import cartsRouter from "./routes/carts.router.js";
import realTimeProductsRouter from "./routes/realTimeProducts.router.js";
import chatRouter from "./routes/chat.router.js";
import handlebars from "express-handlebars";
import sessionsRouter from "./routes/sessions.router.js";
import usersViewRouter from "./routes/users.views.router.js";
import __dirname from "./utils.js";
import { Server } from "socket.io";
import { allowInsecurePrototypeAccess } from "@handlebars/allow-prototype-access";
import mongoose from "mongoose";
import Handlebars from "handlebars";
import "dotenv/config";
import dotenv from "dotenv";
import session from "express-session";
import MongoStore from "connect-mongo";
import passport from "passport";
import initializePassport from "./config/passport.config.js";
dotenv.config();

const app = express();
const PORT = 8080;

const MONGODB_URI = process.env.MONGODB_URI;

app.use(
  session({
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      mongoOptions: { useNewUrlParser: true, useUnifiedTopology: true },
      ttl: 60,
    }),

    secret: "coderS3cr3t",
    resave: false,
    saveUninitialized: false,
  })
);

mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("DB connected"))
  .catch((err) => console.error("Error connecting to the database:", err));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (request, response) => {
  response.send("<h1> Bienvenidos al servidor.</h1>");
});

initializePassport();
app.use(passport.initialize());
app.use(passport.session());

app.use("/api/products", productsRouter);
app.use("/api/carts", cartsRouter);
app.use("/api/sessions", sessionsRouter);
app.use("/api/users", usersViewRouter);

app.engine(
  "hbs",
  handlebars.engine({
    extname: "hbs",
    defaultLayout: "main",
    handlebars: allowInsecurePrototypeAccess(Handlebars),
  })
);
app.set("views", `${__dirname}/views`);
app.set("view engine", "hbs");

app.use(express.static(__dirname + "/public"));

const httpServer = app.listen(PORT, () =>
  console.log("Servidor en el puerto 8080 esta activo.")
);

const io = new Server(httpServer);

app.use("/api/realtimeproducts", realTimeProductsRouter(io));
app.use("/api/chat", chatRouter(io));
