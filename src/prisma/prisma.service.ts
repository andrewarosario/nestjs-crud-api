import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor() {
    super({
      datasources: {
        db: {
          url: 'postgresql://andrewrosario:d@localhost:5432/andrewrosario?schema=public',
        },
      },
    });
  }
}
