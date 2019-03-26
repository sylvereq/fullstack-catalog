from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///items.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

defaultuser = User(name="test", email="test@test.com")
defaultuser.hash_pw("test")
session.add(defaultuser)
session.commit()

category1 = Category(name="Bikes", user=defaultuser)
session.add(category1)
session.commit()

category2 = Category(name="Sports", user=defaultuser)
session.add(category2)
session.commit()

item1 = Item(title="Football", description="nice game",
             imgSource="http://placekitten.com/g/200/300", category=category2,
             user=defaultuser)
session.add(item1)
session.commit()
