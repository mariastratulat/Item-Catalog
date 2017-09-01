from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Car(Base):

    __tablename__ = 'car'

    name = Column(String(250), nullable = False)
    id = Column(Integer, primary_key = True)
    sign = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
      return {
        'name': self.name,
        'id': self.id,
    }

class Model(Base):
    __tablename__ = 'model'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    price = Column(String(20))
    car_class = Column(String(80))
    electric_range = Column(String(250))
    car_id = Column(Integer, ForeignKey('car.id'))
    car = relationship(Car)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
        return {
        'name': self.name,
        'price': self.price,
        'id': self.id,
        'car_class': self.car_class,
        'electric_range': self.electric_range,
        }



engine = create_engine('sqlite:///carswithusers2.db')
Base.metadata.create_all(engine)