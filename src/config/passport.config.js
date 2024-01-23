import passport from "passport";
import passportLocal from "passport-local";
import { userModel } from "../daos/models/user.model.js";
import { createHash, isValidPassword } from "../utils.js";

const localStrategy = passportLocal.Strategy;

const initializePassport = () => {
  passport.use(
    "register",
    new localStrategy({ passReqToCallback: true, usernameField: "email" },
    async (req, username, password, done) => {
      const { first_name, last_name, email } = req.body;

      try {
        const exist = await userModel.findOne({ email });

        if (exist) {
          console.log("El usuario ya existe.");
          done(null, false);
        }

        let user = {
          first_name,
          last_name,
          email,
          password: createHash(password),
        };

        // Asignar el rol "admin" solo si las credenciales coinciden
        if (
          user.email === "adminCoder@coder.com" &&
          password === "Cod3r123"
        ) {
          user.role = "admin";
        } else {
          user.role = "user"; // Asignar un rol predeterminado si no es un administrador
        }

        const result = await userModel.create(user);

        return done(null, result);
      } catch (error) {
        return done("Error registrando al usuario" + error);
      }
    }
  ));

  passport.use(
    "login",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        const { email } = req.body;

        try {
          const user = await userModel.findOne({ email: username });

          if (!user) {
            console.warn("Usuario inexistente:" + username);
            return done(null, false);
          }

          if (!isValidPassword(user, password)) {
            console.warn("Credenciales invalidas");
            return done(null, false);
          }
          return done(null, user);
        } catch (error) {
          return done("Error de login" + error);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      let user = await userModel.findById(id);
      done(null, user);
    } catch (error) {
      console.error("Error deserializando el usuario: " + error);
    }
  });
};

export default initializePassport;
