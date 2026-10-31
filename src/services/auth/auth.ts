import type { UserRepository } from "../../domain/user/repository.js"

import type { AuthService, PasswordHasher, TokenSign, TokenVerify } from "./auth.types.js"

//создаёт сервис авторизации и принимает параметры для него
export function createAuthService(
    repository: UserRepository,
    passwordHasher: PasswordHasher,
    tokenSign: TokenSign,
    tokenVerify: TokenVerify
): AuthService{
    return{
     async register(input){
//приводим эмейл к единому формату
        const email = input.email.trim().toLowerCase()
//хешируем пароль перед базой данных
        const passwordHash = await passwordHasher.hash(input.password)
        const user = await repository.createUser({email, passwordHash})
//возвращаем данные пользователя
        return{
            id: user.id,
            email: user.email
        }
     },
     async login(input){
        const email = input.email.trim().toLowerCase()
        const user = await repository.getByEmail(email)

//проверяем наличие пользователя и правильность пароля
        if(
            !user||!await passwordHasher.verify(user.passwordHash, input.password)
        ){throw new Error("INVALID_DATA")}

//возвращаем данные юзера и токены авторизации
        return{
            user:{
                id: user.id,
                email: user.email
            },
            accessToken: tokenSign.signAccessToken(user.id),
            refreshToken: tokenSign.signRefreshToken(user.id)
        }   
     }, 
     async refresh(refreshToken) {
//проверяем refresh-токен и получаем айди поьзователя
        const userId = tokenVerify.verifyRefreshToken(refreshToken)
        const user = await repository.getById(userId)
        if (!user) throw new Error("INVALID_REFRESH_TOKEN")

//создаём новые токены
        return{
            accessToken: tokenSign.signAccessToken(user.id),
            refreshToken: tokenSign.signRefreshToken(user.id)
        }
     },
     async me(userId) {
//ищем пользователя по его айди
        const user = await repository.getById(userId)
        if (!user) throw new Error("UNAUTHORIZED")
//возвращаем информацию о юзере
        return{
            id: user.id,
            email: user.email
        }
     }
    }
} 
