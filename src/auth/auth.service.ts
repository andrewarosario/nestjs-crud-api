import { Injectable } from "@nestjs/common";

@Injectable({})
export class AuthService {
    signin() { 
        return {message: 'signed in'};
    }

    signup() {
        return {message: 'signed up'};
    }
}