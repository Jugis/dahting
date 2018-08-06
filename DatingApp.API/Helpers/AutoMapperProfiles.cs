using AutoMapper;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using System.Linq;

namespace DatingApp.API.Helpers
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            CreateMap<User, UserForListDTO>()
                .ForMember(dest => dest.PhotoUrl, opt => {
                    opt.MapFrom(src => src.Photos.FirstOrDefault(p => p.IsMain).Url);
                })
                .ForMember(dest => dest.Age, opt => {
                    opt.ResolveUsing(d => d.DateOfBirth.CalculateAge());
                });
            
            CreateMap<User, UserForDetailDTO>()                
                .ForMember(dest => dest.PhotoUrl, opt => {
                    opt.MapFrom(src => src.Photos.FirstOrDefault(p => p.IsMain).Url);
                })
                .ForMember(dest => dest.Age, opt => {
                    opt.ResolveUsing(d => d.DateOfBirth.CalculateAge());
                });
            

            CreateMap<Photo, PhotosForDetailedDTO>();

            CreateMap<UserForUpdateDTO, User>();
            
            CreateMap<PhotoForCreationDto, Photo>();

            CreateMap<Photo, PhotoForReturnDTO>();

            CreateMap<UserForRegisterDTO, User>();
        }
    }
}