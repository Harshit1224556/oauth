import { Request,Response,NextFunction } from "express";


import {verifyaccesstoken} from '../utils/jwt'
import { error } from "node:console";


export const protect = (req:Request,res:Response,next:NextFunction):void =>{

      //Step 1 — Check if token exists in the request
    // Token comes in the header like this: "Bearer abc123"
    
    try{
    const authHeader = req.headers.authorization


    //agar token nh h to kick then out
    if(!authHeader || !authHeader.startsWith('Bearer ')){
        res.status(401).json({error:'No token Provided'})
        return
    }

    const token = authHeader.split(' ')[1]

    const decoded = verifyaccesstoken(token!)

    req.userId = decoded.userId
    next()
}

catch{
    res.status(401).json({error:"Invalid token or request"})
}
}

declare global {
  namespace Express {
    interface Request {
      userId: string
    }
  }
}


