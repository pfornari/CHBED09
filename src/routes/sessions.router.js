import { Router } from "express";
import { userModel } from "../daos/models/user.model.js";
import { createHash, isValidPassword } from "../utils.js";
import passport from "passport";

const router = Router();

router.post(
  "/register",
  passport.authenticate("register", {
    failureRedirect: "api/sessions/fail-register",
  }),
  async (req, res) => {
    try {
      console.log("Registrando usuario:");

      res.status(201).send({
        status: "success",
        message: "Usuario creado con éxito con ID.",
      });
    } catch (error) {
      console.error("Error al registrar usuario:", error);
      res.status(500).send("Error interno del servidor");
    }
  }
);

router.post(
  "/login",
  passport.authenticate("login", {
    failureRedirect: "api/sessions/fail-login",
  }),
  async (req, res) => {
    console.log("Usuario encontrado para login.");

    const user = req.user;
    console.log(user);

    req.session.user = {
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
    };

    res.send({
      status: "success",
      payload: req.session.user,
      message: "¡Primer logueo realizado! :)",
    });
  }
);

router.post("/logout", (req, res) => {
  if (req.session.login || req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        console.error("Error al destruir la sesión:", err);
        res
          .status(500)
          .json({ status: "error", message: "Error al cerrar sesión" });
      } else {
        res
          .status(200)
          .json({ status: "success", message: "Sesión cerrada exitosamente" });
      }
    });
  } else {
    res
      .status(400)
      .json({ status: "error", message: "No hay sesión activa para cerrar" });
  }
});

router.get("/fail-register", (req, res) => {
  res.status(401).send({ error: "Failed to process register!" });
});

router.get("/fail-login", (req, res) => {
  res.status(401).send({ error: "Failed to process login!" });
});

export default router;
