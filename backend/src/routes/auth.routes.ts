import {Router} from 'express'
import { protect } from '../middleware/auth'
import {register,login,logout,refresh,getme} from '../controller/auth.controller'

const router = Router()
router.post('/register', register)
router.post('/login', login)
router.post('/logout', logout)
router.post('/refresh', refresh)
router.get('/me', protect, getme)
export default router