const { response } = require("express");

const esAdminRole = (req, res = response, next) => {
  if (!req.usuarioRol)
    return res
      .status(500)
      .json({ msg: "Se quiere verificar el rol sin validar token primero" });

  const { rol, nombre } = req.usuarioRol;

  if (rol !== "ADMIN_ROLE")
    return res
      .status(401)
      .json({ msg: `${nombre} no es administrador - No puede hacer esto` });

  next();
};

const tieneRol = (...roles) => {
  return (req, res = response, next) => {
    if (!req.usuarioRol)
      return res
        .status(500)
        .json({ msg: "Se quiere verificar el rol sin validar token primero" });

    if (!roles.includes(req.usuarioRol.rol))
      return res
        .status(401)
        .json({ msg: `El servicio requiere uno de estos roles ${roles}` });
    next();
  };
};
module.exports = { esAdminRole, tieneRol };
