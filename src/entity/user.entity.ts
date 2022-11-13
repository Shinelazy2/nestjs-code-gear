import { Column, Entity, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { UserAuthority } from './user-authority.entity';

@Entity('user')
export class User {
  @PrimaryGeneratedColumn({ type: 'int', name: 'id' })
  id: number;

  @Column('varchar', { name: 'kakao_id', length: 45 })
  kakaoId: string;

  @Column('varchar', { name: 'email', nullable: true, length: 100 })
  email: string;

  @Column('varchar', { name: 'name', nullable: true, length: 45 })
  name: string | null;

  @Column('varchar', { name: 'gender', nullable: true, length: 10 })
  gender: string;

  @Column('varchar', { name: 'phone', nullable: true, length: 20 })
  phone: string;

  @Column('varchar', { name: 'birth', nullable: true, length: 10 })
  birth: string;

  @Column('varchar', { name: 'profile_image', nullable: true, length: 200 })
  profileImage: string | null;

  @Column({
    name: 'created_at',
    nullable: true,
    default: () => 'CURRENT_TIMESTAMP',
  })
  createdAt: Date | null;

  @Column({
    name: 'updated_at',
    nullable: true,
    default: () => 'CURRENT_TIMESTAMP',
  })
  updatedAt: Date | null;

  @OneToMany(() => UserAuthority, (userAuthority) => userAuthority.user, {
    eager: true,
  })
  authorities?: any[];
}
