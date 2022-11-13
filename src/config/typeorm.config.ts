import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';

@Injectable()
export class TypeOrmConfigService implements TypeOrmOptionsFactory {
  constructor(private configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: 'sqlite',
      database: this.configService.get<string>('DB_NAME'),
      entities: [__dirname + '**/*.entity{.ts,.js}'],
      synchronize: true,
      migrations: ['migrations/*.js'],
      autoLoadEntities: true,
    };
  }
}
