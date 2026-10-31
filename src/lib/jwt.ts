import "dotenv/config"
import jwt from "jsonwebtoken";

//получаем секретные ключи 
const accessSecret = process.env.JWT_ACCESS_SECRET;
const refreshSecret = process.env.JWT_REFRESH_SECRET;
//проверяем, что ключи заданы
if (!accessSecret) throw new Error("JWT_ACCESS_SECRET is not defined");
if (!refreshSecret) throw new Error("JWT_REFRESH_SECRET is not defined");

//создаём токен доступа с ограниченным временем действия
export function signAccessToken(userId: number): string {
  return jwt.sign({}, accessSecret!, {
    algorithm: "HS256",          
    subject: String(userId),     
    expiresIn: "15m",            
  });
}

//создаём токен для обновления авторизации
export function signRefreshToken(userId: number): string {
  return jwt.sign({type: "refresh"}, refreshSecret!, {
    algorithm: "HS256",          
    subject: String(userId),   
//количество дней действия токена  
    expiresIn: "7d",            
  });
}

//проверяем access-токен и получаем айди юзера
export function verifyAccessToken(token: string): number {
  try {
    const payload = jwt.verify(token, accessSecret!, {
      algorithms: ["HS256"] 
    })
//проверяем формат полученных данных
    if (typeof payload === "string" || typeof payload.sub !== "string" ) {
      throw new Error()
    }
    const userId = Number(payload.sub)
//проверяем, что айди является целым числом
    if (!Number.isSafeInteger(userId) || userId <= 0) {
      throw new Error()
    }
    return userId
  }
  catch {
//возвращаем ошибку, если токен недействителен
    throw new Error("INVALID_ACCESS_TOKEN")
  }
}

//проверяем refresh-токен и получаем айди
export function verifyRefreshToken(token: string): number {
  try {
    const payload = jwt.verify(token, refreshSecret!, {
      algorithms: ["HS256"] 
    })
//проверяем тип токена и наличие айди
    if (typeof payload === "string" || typeof payload.sub !== "string" || payload.type !== "refresh" ) {
      throw new Error()
    }
    const userId = Number(payload.sub)
    if (!Number.isSafeInteger(userId) || userId <= 0) {
      throw new Error()
    }
    return userId
  }
  catch {
//обработка ошибки и проверки refresh-токена
    throw new Error("INVALID_REFRESH_TOKEN")
  }
}