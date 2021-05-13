/*
    path: api/login
 */
const { Router } = require("express");
const router = Router()
const { check } = require("express-validator");
//Controladores
const { crearUsusario, login, renewToken } = require("../controllers/auth");
const { validarCampos } = require("../middlewares/validar-campos");
const { validarJWT } = require("../middlewares/validar-jwt");

// Crear nuevo usuario
router.post('/new', [
    check('nombre', 'El nombre es obligatorio').not().isEmpty(),
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'El password es obligatorio').not().isEmpty(),
    validarCampos
], crearUsusario)

// Login
router.post('/', [
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'El password es obligatorio').not().isEmpty(),
    validarCampos
], login)

// Revalidar Token
router.get('/renew', validarJWT, renewToken)


module.exports = router