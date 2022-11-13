import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, VerifiedCallback } from 'passport-jwt';
import { AuthService } from '../auth.service';
import { Payload } from './payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: true,
      secretOrKey: configService.get<string>('SECERT_KEY'),
    });
  }

  async validate(payload: Payload, done: VerifiedCallback): Promise<any> {
    const user = await this.authService.tokenValidateuser(payload);
    if (!user) {
      return done(
        new UnauthorizedException({ message: '유저가 조회되지 않음' }),
        false,
      );
    }

    return done(null, user);
  }
}
