const { Router } = require("express");
const { body, check } = require("express-validator");

const { login } = require("../controllers/auth");
const { validarCampos } = require("../middlewares/validar-campos");

const router = Router();

router.post(
  "/login",
  [
    body("correo", "El correo es obligatorio").isEmail(),
    body("password", "La contraseña es obligatoria").not().isEmpty(),
    validarCampos,
  ],
  login
);

module.exports = router;
