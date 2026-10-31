import type { PublicUser } from "../../domain/user/entity";

//данные для регистрации и входа юзера
export interface AuthInput {
    email: string , 
    password: string
}

//методы для хеша пароля и проверки
export interface PasswordHasher {
    hash(password: string): Promise<string> , 
    verify(password: string, hash: string):  Promise<boolean>
}

//интерфейс для создания токенов пользователей
export interface TokenSign {
    signAccessToken(userId: number): string
    signRefreshToken(userId: number): string
}

//отвечает за проверку рефреш токена и получает айди юзера
export interface TokenVerify{
    verifyRefreshToken(token: string): number
}

//содержит токены для авторизации
export interface AuthTokens{
    accessToken: string
    refreshToken: string
}

//определяет методы для сервис авторизации
export interface AuthService {
//новый аккаунт
    register(input: AuthInput): Promise<PublicUser> 
//проверка данных и вход
    login(input: AuthInput): Promise<{user: PublicUser} & AuthTokens>
//получение новых токенов
    refresh(refreshToken: string): Promise<AuthTokens>
//получение данных нового пользователя
    me(userId: number): Promise<PublicUser>
}