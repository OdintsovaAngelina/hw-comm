import type { RequestHandler } from "express";

//Создаём middlewares для проверки авторизации
export function createRequireAuth(
//проверяет токен и возвращает его
    verifyAccessToken: (token: string)=> number
): RequestHandler{
    return (req, res, next)=>{
//получаем токен из кукис
        const token = req.cookies?.accessToken
//проверяем есть ли токен и является ли он строкой
        if (typeof token !== "string"){
            res.status(401).json({message: "Unauthorized"})
            return 
        }
        try{
//проверяем токен и сохраняем айди пользователя в res.locals
            res.locals.userId = verifyAccessToken(token)
//передаём управление следующему middlewares
            next()
        } catch{
//если токен неработает, то возвращаем ошибку
            res.status(401).json({message: "Unauthorized"})
        }
    }
}