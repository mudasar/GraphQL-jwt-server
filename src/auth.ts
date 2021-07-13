import { sign } from "jsonwebtoken";
import { User } from "./entity/User";

export const createAccessToken = (user: User) => {
    return sign({userId: user.id, email: user.email, tokenVersion: user.tokenVersion}, process.env.ACCESS_TOKEN_SECRET, { 
        algorithm: "HS512",
        expiresIn: '15s'
    });
}
export const createRefreshToken = (user: User) => {
    return sign({userId: user.id, email: user.email, tokenVersion: user.tokenVersion}, process.env.REFRESH_TOKEN_SECRET, { 
        algorithm: "HS512",
        expiresIn: '7d'
    });
}