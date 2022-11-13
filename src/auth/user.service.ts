import { UserAuthority } from './../entity/user-authority.entity';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/entity/user.entity';
import { FindOneOptions, Repository } from 'typeorm';
import { RoleType } from './role-type';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(UserAuthority)
    private userAuthorityRepository: Repository<UserAuthority>,
  ) {}

  async findByFileds(options: FindOneOptions<User>): Promise<User | undefined> {
    return await this.userRepository.findOne(options);
  }

  async registerUser(user: User): Promise<User> {
    const registeredUser = await this.save(user);

    if (registeredUser) {
      // 권한 추가
      await this.saveAuthority(registeredUser.id);
    } else {
      throw new HttpException(
        '회원 가입 에러',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    return registeredUser;
  }
  async saveAuthority(id: number): Promise<UserAuthority | undefined> {
    const userAuth = new UserAuthority();
    userAuth.userId = id;
    userAuth.authorityName = RoleType.USER;
    return await this.userAuthorityRepository.save(userAuth);
  }

  async save(user: User): Promise<User | undefined> {
    return await this.userRepository.save(user);
  }
}
