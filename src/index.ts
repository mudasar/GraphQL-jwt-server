/* eslint-disable import/first */
require('dotenv').config({path: __dirname + '/.env'});
import "reflect-metadata";
import express from "express";
import {ApolloServer} from "apollo-server-express";
import {createConnection} from "typeorm";
import { buildSchema } from "type-graphql";
import { UserResolver } from "./UserResolver";
import cookieParser from 'cookie-parser';
import { verify } from "jsonwebtoken";
import { User } from './entity/User';
import { createAccessToken, createRefreshToken } from "./auth";
import cors from 'cors';
// console.log(process.env);


const corsOptions = {
    origin: ["http://localhost:3000", "https://studio.apollographql.com"],
    credentials: true
};

(async () => {

    //CORS middleware
    const allowCrossDomain = (req, res, next) => {
        console.log(req.headers.origin);
        res.header('Access-Control-Allow-Origin', req.headers.origin);
        res.setHeader('Access-Control-Request-Method', '*');
        res.header('Access-Control-Allow-Methods', 'OPTIONS,GET,PUT,POST,DELETE');
        res.header('Access-Control-Allow-Headers', '*');
        res.header('Access-Control-Allow-Credentials', 'true');

        next();
    }

    const app = express();
    //app.use(allowCrossDomain);
    app.use(cors(corsOptions));
    app.options('*', cors());
    app.use(cookieParser());

    app.get('/', (req, res) => {
        res.send('hello');
    });

    app.post('/refresh-token', async (req, res) => {
        // console.log(req.cookies);

        const token = req.cookies.jid;
        if(!token){
            return res.send({ok: false, accessToken:''})
        }

        let payload = null;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
            
        } catch (e) {
            console.log(e);
            return res.send({ok: false, accessToken:''})
        }

        // we have a valid token
        const user = await User.findOne({id: payload.userId});
        if(!user){
            return res.send({ok: false, accessToken:''})
        }

        if (user.tokenVersion !== payload.tokenVersion) {
            return res.send({ok: false, accessToken:''})
        }

        res.cookie('jid', createRefreshToken(user), { httpOnly: true, path: '/refresh-token'});

        return res.send({ok: true, accessToken: createAccessToken(user)})


    });

    await createConnection();

    const apolloServer = new ApolloServer({
        schema: await buildSchema({
                resolvers: [UserResolver]
            }
        ),
        context: ({req, res}) => ({req, res})
    });

    await apolloServer.start();

    apolloServer.applyMiddleware({ app, cors: false });

    app.listen(4000, () => {
        console.log('Server is listening on port http://localhost:4000');
    })

})();
