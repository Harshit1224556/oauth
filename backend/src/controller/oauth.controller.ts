import { Request, Response } from 'express'
import crypto from 'crypto'
import prisma from '../utils/prisma'
import { generateaccesstoken, generaterefreshtoken } from '../utils/jwt'

// Helper function — reused by both Google and GitHub
const handleOAuthSuccess = async (req: Request, res: Response) => {
  try {
    const user = req.user as { id: string; email: string }

    if (!user) {
      res.redirect(`${process.env.CLIENT_URL}/login?error=oauth_failed`)
      return
    }

    const accessToken = generateaccesstoken(user.id)
    const refreshToken = generaterefreshtoken(user.id)

    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex')

    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.redirect(`${process.env.CLIENT_URL}/auth/callback?token=${accessToken}`)
  } catch {
    res.redirect(`${process.env.CLIENT_URL}/login?error=server_error`)
  }
}

export const googleCallback = handleOAuthSuccess


export const githubCallback = handleOAuthSuccess