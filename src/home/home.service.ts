import { Injectable, NotFoundException } from '@nestjs/common';
import { PropertyType } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { HomeResponseDto } from './dto/home.dto';

interface GetHomesParams {
  city?: string;
  price?: {
    gte?: number;
    lte?: number;
  };
  propertyType?: PropertyType;
}

@Injectable()
export class HomeService {
  constructor(private readonly prismaService: PrismaService) {}
  async getHomes(filter: GetHomesParams): Promise<HomeResponseDto[]> {
    const homes = await this.prismaService.home.findMany({
      select: {
        id: true,
        address: true,
        city: true,
        price: true,
        propertyType: true,
        number_of_bathrooms: true,
        number_of_Bedrooms: true,
        images: {
          select: {
            url: true,
          },
          take: 1,
        },
      },
      where: filter,
    });

    if (!homes.length) {
      throw new NotFoundException();
    }

    return homes.map((home) => {
      const fetchHome = { ...home, image: home.images[0].url };
      delete fetchHome.images;
      return new HomeResponseDto(fetchHome);
    });
  }

  async getHomeById(id: number) {
    const home = await this.prismaService.home.findUnique({
      where: {
        id,
      },
    });
    if (!home) {
      throw new NotFoundException();
    }
    return new HomeResponseDto(home);
  }
}
