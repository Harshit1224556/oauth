import { Router } from 'express'
import passport from '../utils/passport'
import { googleCallback, githubCallback } from '../controller/oauth.controller'

const router = Router()

// ─── GOOGLE ─────────────────────────────────────────────
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })
)

router.get('/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login?error=google_failed' }),
  googleCallback
)

// ─── GITHUB ─────────────────────────────────────────────
router.get('/github',
  passport.authenticate('github', { scope: ['user:email'], session: false })
)

router.get('/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/login?error=github_failed' }),
  githubCallback
)

export default router