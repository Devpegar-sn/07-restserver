const Role = require("../models/role");
const Usuario = require("../models/usuario");

const esRoleValido = async (rol = "") => {
  const existeRol = await Role.findOne({ rol });
  if (!existeRol) {
    throw new Error(`El rol ${rol} no esta registrdo en la base de datos`);
  }
};

const validarEmail = async (correo) => {
  const existeEmail = await Usuario.findOne({ correo });
  if (existeEmail) {
    throw new Error("El correo ya existe en la base de datos");
  }
};

const validarUsuarioExiste = async (id) => {
  const existeUsuario = await Usuario.findById(id);
  if (!existeUsuario) {
    throw new Error(`El ID ${id} no esta registrdo en la base de datos`);
  }
};

module.exports = { esRoleValido, validarEmail, validarUsuarioExiste };
