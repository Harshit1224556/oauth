import { Request,Response } from "express";
import bycrypt from 'bcryptjs'
import crypto from 'crypto'
import prisma from "../utils/prisma";
import {
    generateaccesstoken,
    generaterefreshtoken,
    verifyaccesstoken
} from '../utils/jwt'
import { error } from "console";
 

export const register = async(req:Request,res:Response):Promise<void>=>{

    try{
        const {email,password} = req.body
        const existing = await prisma.user.findUnique({where:{email}})
        if(existing){
            res.status(400).json({error:'Email already in use'})
            return
        }
        const passwordHash = await bycrypt.hash(password,12)
        const user = await prisma.user.create({
            data:{email,passwordHash}
        })
        res.status(201).json({
            message:'user create successfully',
            user:{id:user.id,email:user.email}
        })
    }
    catch{
            res.status(500).json({error:'Something went wrong'})
    }
}

export const login = async(req:Request,res:Response):Promise<void> =>{
    try{
    const {email,password} = req.body

    const user = await prisma.user.findUnique({where:{email}})

    if(!user||!user.passwordHash){
        res.status(401).json({error:"Invalid password or email"})
        return
    }

    const ismatch = await bycrypt.compare(password,user.passwordHash)

    if(!ismatch){
        res.json({
            error:"Invalid email or password"
            
        })

        return
    }
    

    const accesstoken = generateaccesstoken(user.id)
    const refreshtoken = generateaccesstoken(user.id)

    const tokenHash = crypto.createHash('sha256')
    .update(refreshtoken)
    .digest('hex')


    await prisma.refreshToken.create({
        data: {
            userId:user.id,
            tokenHash,
            expiresAt:new Date(Date.now() + 7*24*60*60*1000)

        },
    })

    res.cookie('refreshToken',refreshtoken,{
        httpOnly:true,
        secure:true,
        sameSite:'strict',
        maxAge:7*24*60*60*1000
    })

    res.json({
        accesstoken,
        user:{id:user.id,email:user.email,isVerified:user.isVerified}
    })
}
catch{
    res.status(500).json({error:'Something went wrong'})
}

} 

