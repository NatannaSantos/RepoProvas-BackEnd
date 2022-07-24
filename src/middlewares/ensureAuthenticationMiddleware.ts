import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { unauthorizedError } from "../../utils/errorUtils.js";
import * as userService from "../services/userService.js";
import dotenv from "dotenv";

dotenv.config();

export async function ensureAuthenticationMiddleware(req: Request, res: Response, next: NextFunction) {

    const authorization = req.headers["authorization"];
    const token = authorization.replace("Bearer ", "");

    if (!token) throw unauthorizedError("Missing authorization header");

    try {
        const { userId } = jwt.verify(token, process.env.JWT_SECRET) as {
            userId: number;
        };

        const user = await userService.findById(userId);
        res.locals.user=user;

        next();

    } catch {
        unauthorizedError("Invalid token");
    }
}