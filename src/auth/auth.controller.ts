import { AuthGuard } from './security/auth.guard';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Response,
  UnauthorizedException,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/login')
  async login(@Body() body: any, @Response() res): Promise<any> {
    try {
      const { code, domain } = body;
      if (!code || !domain) {
        throw new BadRequestException('요청 오류');
      }
      // Kakao 로그인
      const kakao = await this.authService.kakaoLogin({ code, domain });

      if (!kakao.id) {
        throw new UnauthorizedException('카카오 로그인 실패');
      }

      // 로컬 로그인 처리
      const jwt = await this.authService.login(kakao);

      res.send({
        accessToken: jwt.accessToken,
        message: 'success',
      });
    } catch (err) {
      // console.log(err);
    }
  }

  // 사용자 정보 조회
  @UseGuards(AuthGuard)
  @Get('/user')
  getUser(@Request() req): any {
    // console.log(req);
    return req.user;
  }
}
