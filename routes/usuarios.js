const { Router } = require("express");
const { body, check } = require("express-validator");

const { validarCampos } = require("../middlewares/validar-campos");
const {
  esRoleValido,
  validarEmail,
  validarUsuarioExiste,
} = require("../helpers/db-validators");

const {
  usuariosGet,
  usuariosPut,
  usuariosPost,
  usuariosDelete,
  usuariosPatch,
} = require("../controllers/usuarios");

const router = Router();

router.get("/", usuariosGet);
router.post(
  "/",
  // Utilizo el middleware body para especificar que lea solo el body de la request
  [
    body("nombre", "El campo nombre no puede estar vacio").not().isEmpty(),
    body("correo", "El correo no es valido").isEmail(),
    body("correo", "El correo no es valido").custom(validarEmail),
    body(
      "password",
      "La contraseña debe tener un minimo de 8 caracteres"
    ).isLength({ min: 8, max: 30 }),
    body("rol").custom(esRoleValido),
    validarCampos,
  ],
  usuariosPost
);
router.put(
  "/:id",
  // Utilizo check para tomoar de la url el id
  [
    check("id", "No es un ID valido").isMongoId(),
    check("id").custom(validarUsuarioExiste),
    body("rol").custom(esRoleValido),
    validarCampos,
  ],
  usuariosPut
);
router.patch("/", usuariosPatch);

router.delete(
  "/:id",
  [
    check("id", "No es un ID valido").isMongoId(),
    check("id").custom(validarUsuarioExiste),
    validarCampos,
  ],
  usuariosDelete
);

module.exports = router;
