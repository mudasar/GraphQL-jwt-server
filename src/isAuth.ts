import {   MiddlewareFn } from "type-graphql";
import { MyContext } from "./MyContext";
import { verify } from 'jsonwebtoken';

export const isAuth: MiddlewareFn<MyContext> = ({context}, next) => {

    // console.log(context.req.headers);
    const authorization = context.req.headers['authorization'] as string;
    if (!authorization) {
        throw new Error('Not authenticated');
    }
    try {
        const token = authorization.split(' ')[1];
        const payload = verify(token, process.env.ACCESS_TOKEN_SECRET);
        context.payload = payload as any;
    } catch (e) {
        console.log(e);
        throw new Error('Invalid token');
    }


    return next();
}