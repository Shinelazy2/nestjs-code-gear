import { JwtStrategy } from './security/passport.jwt.strategy';
import { UserAuthority } from './../entity/user-authority.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from 'src/entity/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { UserService } from './user.service';

@Module({
  imports: [
    HttpModule,
    TypeOrmModule.forFeature([User, UserAuthority]),
    // JwtModule.register({
    //   secret: configService,
    // }),
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '300s' },
    }),
    PassportModule,
  ],
  exports: [TypeOrmModule, AuthService, UserService],
  controllers: [AuthController],
  providers: [AuthService, UserService, JwtStrategy],
})
export class AuthModule {}
