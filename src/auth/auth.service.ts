import { RoleType } from './role-type';
import { UserService } from './user.service';
import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import * as qs from 'qs';
import { lastValueFrom } from 'rxjs';
import { User } from 'src/entity/user.entity';
import { Payload } from './security/payload.interface';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly httpService: HttpService,
    private readonly userService: UserService,
    private jwtService: JwtService,
  ) {}

  async tokenValidateuser(payload: Payload): Promise<User | undefined> {
    const userFind = await this.userService.findByFileds({
      where: { id: payload.id },
    });

    this.flatAuthorities(userFind);
    return userFind;
  }

  flatAuthorities(user: any): any {
    if (user && user.authorities) {
      const authorities: string[] = [];
      user.authorities.forEach((authority) => {
        authorities.push(authority.authorityName);
      });
      user.authorities = authorities;

      for (const auth of authorities) {
        if (auth === RoleType.ADMIN) {
          user.isAdmin = true;
        }
      }
    }
    // console.log(user);

    return user;
  }

  async kakaoLogin(options: { code: string; domain: string }): Promise<any> {
    const { code, domain } = options;
    const kakaoKey = '0a054e28c569c2b4a4e0734274cb2786';
    const kakaoTokenUrl = 'https://kauth.kakao.com/oauth/token';
    const kakaoUserInfoUrl = 'https://kapi.kakao.com/v2/user/me';
    const body = {
      grant_type: 'authorization_code',
      client_id: kakaoKey,
      redirect_uri: `${domain}/kakao-callback`,
      code,
    };
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
    };
    try {
      const res = this.httpService.post(kakaoTokenUrl, qs.stringify(body), {
        timeout: 30000,
        headers,
      });

      const response = await lastValueFrom(res);

      if (response.status === 200) {
        // console.log(
        //   `kakaoToken 로그인했음 : ${JSON.stringify(response.data.length)}`,
        // );
        // Token 을 가져왔을 경우 사용자 정보 조회

        const headerUserInfo = {
          'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
          Authorization: 'Bearer ' + response.data.access_token,
        };
        // console.log(`url : ${kakaoTokenUrl}`);
        // console.log(`headers : ${JSON.stringify(headerUserInfo)}`);

        const resUserInfo = this.httpService.get(kakaoUserInfoUrl, {
          timeout: 30000,
          headers: headerUserInfo,
        });

        const responseUserInfo = await lastValueFrom(resUserInfo);

        // console.log(`responseUserInfo.status : ${responseUserInfo.status}`);
        if (responseUserInfo.status === 200) {
          // console.log(
          //   `kakaoUserInfo : ${JSON.stringify(responseUserInfo.data)}`,
          // );
          return responseUserInfo.data;
        } else {
          throw new UnauthorizedException();
        }
      } else {
        throw new UnauthorizedException();
      }
    } catch (error) {
      // console.log(error);
      throw new UnauthorizedException();
    }
  }

  async login(kakao: any): Promise<{ accessToken: string | undefined }> {
    let userFind: User = await this.userService.findByFileds({
      where: { kakaoId: kakao.id },
    });

    if (!userFind) {
      const user = new User();
      user.kakaoId = kakao.id;
      user.email = kakao.kakao_account.email;
      user.name = kakao.kakao_account.name;
      userFind = await this.userService.registerUser(user);
    }

    const payload: Payload = {
      id: userFind.id,
      name: userFind.name,
      authorities: userFind.authorities,
    };

    return {
      accessToken: this.jwtService.sign(payload),
    };
  }
}
