import { Request,Response } from "express";
import bycrypt from 'bcryptjs'
import crypto from 'crypto'
import prisma from "../utils/prisma";
import {
    generateaccesstoken,
    generaterefreshtoken,
    verifyaccesstoken,
    verifyrefreshtoken
} from '../utils/jwt'
import { error } from "console";
 

// this is the register controller
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


// this is my login controller 
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


//this is my refreshtoken controller
//OLD TOKEN → verify → revoke → generate NEW → store → send
export const refresh = async(req:Request,res:Response):Promise<void> =>{
    try{


        const token = req.cookies?.refreshToken;
        if(!token)
        {
            res.status(401).json({
                message:"No refresh token provided"
                
            })

            return
        }
       
        //token ek variable m store kr liya agar token nh h to remove kr diya h us token ko 

        let decoded;

        
             
            decoded=verifyrefreshtoken(token)
        

       

        const tokenHash = crypto.createHash('sha256').update(token).digest('hex')

        const stored = await prisma.refreshToken.findUnique({where:{tokenHash}})

        if(!stored || stored.revoked || stored.expiresAt<new Date()){

            res.status(401).json({
                error:'Invalid refresh token'
            })
        }

        await prisma.refreshToken.update({
            where:{tokenHash},
            data:{revoked:true}
        })

        const newaccesstoken = generateaccesstoken(decoded.userId);
        const newRefreshtoken = generaterefreshtoken(decoded.userId);

        const newTokenHash = crypto.createHash('sha256').update(newRefreshtoken).digest('hex');

        await prisma.refreshToken.create({

            data:{
                userId:decoded.userId,
                tokenHash:newTokenHash,
                 expiresAt:new Date(Date.now()*7*24*60*60*1000)

            },
        })

        res.cookie('refreshToken',newRefreshtoken,{
            httpOnly:true,
            sameSite:'strict',
            maxAge:7*24*60*60*1000
        })

         res.json({
            accesstoken:newaccesstoken
         })

    }



    catch(error){
        console.error("Refresh error",error);
        res.status(500).json({
            error:"Something went wrong"
        })
    }
}




export const logout = async(req:Request,res:Response):Promise<void> =>{
 
       try{
            
        const token = req.cookies.refreshToken
        if(token){
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
            await prisma.refreshToken.updateMany({
                where:{tokenHash},
                data:{revoked:true}
            })
        }
        res.clearCookie('refreshToken')

        res.json({
            message:"Logout successfully"
        })
       }

       catch{
        res.status(500).json({
            message:"Something went wrong"
        })
       }

}


export const getme = async(req:Request,res:Response):Promise<void> =>{

    try{
         const user =  await prisma.user.findUnique({
            where:{id:req.userId},
            select:{
               id:true,
               email:true,
               isVerified:true,
               createdAt:true 
            }
          })

          if(!user){
            res.status(404).json({
                message:'user not found'
            })
            return
          }

          res.json({user})

    }
    catch{
        res.status(500).json({
            error:'Something went wrong'
        })
    }

}


