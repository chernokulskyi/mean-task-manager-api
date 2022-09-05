import mongoose from 'mongoose';

const ListSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    minLength: 1,
    trim: true
  },
  _userId: {
    type: mongoose.Types.ObjectId,
    required: true
  }
});

export const List = mongoose.model('List', ListSchema);