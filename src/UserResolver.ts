import { Arg, Ctx, Field, Int, Mutation, ObjectType, Query, Resolver, UseMiddleware } from "type-graphql";
import * as bcrypt from 'bcryptjs';
import { User } from "./entity/User";
import { MyContext } from "./MyContext";
import { createAccessToken, createRefreshToken } from './auth';
import { isAuth } from "./isAuth";
import { getConnection } from "typeorm";


@ObjectType()
export class LoginResponse {
    
    @Field()
    accessToken: string;
    @Field()
    user: User;
}


@Resolver()
export class UserResolver {
    @Query(() => String)
    hello() {
        return 'hi';
    }
    
    @Query(() => String)
    @UseMiddleware(isAuth)
    bye(@Ctx() {payload}: MyContext) {
        return `your user id is ${payload.userId}`;
    }
    
    @Query(() => User, {nullable: true})
    @UseMiddleware(isAuth)
    async me(@Ctx() {payload}: MyContext) {
        try {
            const user = await User.findOne(payload.userId);
            return user;
        } catch (error) {
            return null
        }
    }

    @Query(() => [User])
    users() {
        return User.find();
    }

    @Mutation(() => Boolean)
    async register(
        @Arg('email', () => String) email: string,
        @Arg('password', () => String) password: string) {

            try {            
                const hashedPassword = await bcrypt.hash(password, 12);
                const user = await User.insert({email, password: hashedPassword});
                console.log(user);
                return true;
            } catch (e) {
                console.log(e);
                return false;
            }
    }

    @Mutation(() => Boolean)
    async revokeRefreshTokensForUser(@Arg('userId', () => Int) userId: number) {
        await getConnection().getRepository(User).increment({id: userId}, "tokenVersion", 1);
        return true;
    }

    @Mutation(() => LoginResponse)
    async login(
        @Arg('email', () => String) email: string,
        @Arg('password', () => String) password: string,
        @Ctx() {req, res}:MyContext
        ): Promise<LoginResponse> {

            const user = await User.findOne({where: {email: email}});
            if (!user) {
                throw new Error('Invalid email or password');
            }
            const valid = await bcrypt.compare(password, user.password);
            if (!valid) {
                throw new Error('Invalid email or password');
            }
            res.cookie('jid', createRefreshToken(user), { httpOnly: true, path: '/refresh-token'});

            return {
                accessToken: createAccessToken(user),
                user
            };
    }

    @Mutation(() => Boolean)
    async logout(@Ctx() {req, res}:MyContext){
        res.cookie('jid', '', { httpOnly: true, path: '/refresh-token'})
        return true;
    }
}