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
        const passwordhash = await bycrypt.hash(password,12)
        const user = await prisma.user.create({
            data:{email,passwordhash}
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

