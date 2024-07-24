import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { JwtPaylod } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor( private jwtService: JwtService,
    private authService: AuthService
   ){}

  async canActivate( context: ExecutionContext ): Promise<boolean>{
    const request = context.switchToHttp().getRequest()
    const token = this.extractTokenFromHeader( request )

    if( !token ){
      throw new UnauthorizedException('There is not a token access')
    }
    try {
      const payload = await this.jwtService.verifyAsync<JwtPaylod>(
        token,{ secret: process.env.JWT_SEED }
      )
      const user = await  this.authService.findUserById( payload.id )
      if( !user ) throw new UnauthorizedException('user does not exist')
      if( !user.isActive ) throw new UnauthorizedException('user is not active')
      request['user'] = user
    } catch (error) {
      throw new UnauthorizedException()
    }
    return Promise.resolve(true)
  }

  private extractTokenFromHeader( request: Request ): string | undefined{
    const [ type, token ] = request.headers['authorization']?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
