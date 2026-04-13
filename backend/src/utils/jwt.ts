import jwt from 'jsonwebtoken'
import { StringDecoder } from 'node:string_decoder'

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET!
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!

export const generateaccesstoken = (userId:string):string=>{
    return jwt.sign({userId},ACCESS_SECRET,{expiresIn:'15m'})
}

export const generaterefreshtoken = (userId:string):string=>{
    return jwt.sign({userId},REFRESH_SECRET,{expiresIn:'7d'})
}


export const verifyaccesstoken = (token:string)=>{

     return jwt.verify(token,ACCESS_SECRET) as {userId:string}
}

export const verifyrefreshtoken =(token:string)=>{
    return jwt.verify(token,REFRESH_SECRET) as {userId:string}
}

//access token is for shorted amount of time 

// is like a band for a club

// and refresh token is like a membership for the club at
// the starting uuu need only not always uu need
